# Enterprise Multi-Company Task Management System

A comprehensive web-based task management platform designed for multi-company operations with sophisticated role-based access control and automated workflow management.

## 🚀 Overview

This enterprise-level system streamlines job creation, approval processes, task assignment, and resource management across different organizational hierarchies. The platform supports multiple companies with complete data isolation while maintaining shared user role definitions and workflows.

## ✨ Key Features

### 🔐 Advanced Role-Based Access Control (RBAC)
- **6+ User Roles**: Super Admin, Company Admin, Engineer, Supervisor, Technical Officer, Employee
- **Granular Permissions**: Custom middleware with numerical permission codes (e.g., '11.20', '12.5')
- **Multi-Company Architecture**: Complete data isolation between organizations
- **Dynamic Route Protection**: Role-based access control at route level

### 📋 Comprehensive Job Management
- **Job Creation**: Supervisors create jobs with descriptions, priorities, job types, and photo attachments
- **Dynamic Field Population**: Equipment and client fields auto-populate based on job type
- **Multi-Stage Approval**: Technical Officers can complete simple jobs or request approval for complex ones
- **Status Tracking**: Real-time status updates (Pending → In Progress → Completed → Closed)

### ⚙️ Advanced Task Management
- **Multi-User Assignment**: Engineers assign multiple employees to individual tasks
- **Deadline Management**: Task scheduling with start/end dates and duration tracking
- **Extension Workflow**: Employees can request deadline extensions with approval process
- **Timeline Visualization**: Interactive job progress tracking with task details

### 📦 Inventory & Resource Management
- **Item Integration**: Add existing inventory items to jobs with quantity management
- **New Item Requests**: Request new items not in current inventory
- **Approval Workflow**: Engineers review and modify item quantities during approval
- **Resource Tracking**: Complete audit trail for all inventory movements

### 🔄 Intelligent Workflow Automation
- **Approval Process**: Multi-stage approval with dynamic item adjustments
- **Job Copying**: Complete job duplication with tasks and items
- **Extension Management**: Automated timeline updates for approved extensions
- **Activity Logging**: Comprehensive audit trail for compliance

## 🏗️ Technical Architecture

### Backend Stack
- **Framework**: Laravel 9+ (PHP)
- **Database**: MySQL with complex relational design
- **Authentication**: Custom session-based authentication
- **Architecture**: MVC pattern with service layer

### Database Design
```
📊 Core Tables:
├── users (Multi-company user management)
├── user_roles (Role definitions)
├── user_role_details (Granular permissions)
├── companies (Multi-tenant support)
├── jobs (Core job management)
├── tasks (Task definitions)
├── job_users (Task assignments)
├── job_items (Inventory management)
├── job_approval_requests (Approval workflow)
├── task_extension_requests (Extension management)
└── logs (Audit trail)
```

### Key Design Patterns
- **Repository Pattern**: Data access abstraction
- **Service Layer**: Business logic separation
- **Observer Pattern**: Activity logging
- **Middleware Chain**: Permission validation

## 🛠️ Installation & Setup

### Prerequisites
- PHP >= 8.0
- Composer
- MySQL >= 5.7
- Node.js & NPM (for asset compilation)

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ThanujaJeewanthi/task_manager.git
   cd task_manager
   ```

2. **Install dependencies**
   ```bash
   composer install
   npm install
   ```

3. **Environment setup**
   ```bash
   cp .env.example .env
   php artisan key:generate
   ```

4. **Database configuration**
   ```bash
   # Update .env with your database credentials
   DB_CONNECTION=mysql
   DB_HOST=127.0.0.1
   DB_PORT=3306
   DB_DATABASE=task_management
   DB_USERNAME=your_username
   DB_PASSWORD=your_password
   ```

5. **Run migrations and seeders**
   ```bash
   php artisan migrate
   php artisan db:seed
   ```

6. **Compile assets**
   ```bash
   npm run dev
   ```

7. **Start the server**
   ```bash
   php artisan serve
   ```

## 🔧 Configuration

### Role & Permission Setup
The system uses numerical permission codes for granular access control:

```php
// Example permission codes
'1.2' => 'Super Admin Dashboard Access'
'11.10' => 'Job Creation Permission'
'11.19' => 'Job Approval Permission'
'12.1' => 'Task Extension Request'
```

### Multi-Company Setup
Each company operates independently with isolated data:
- Users belong to specific companies
- Jobs and tasks are company-scoped
- Permissions are role-based but company-isolated

## 📱 User Workflows

### Job Creation Workflow
1. **Supervisor** creates job with details and priority
2. **System** auto-populates relevant fields based on job type
3. **Technical Officer** receives assignment notification
4. **Technical Officer** reviews and either:
   - Completes job directly (simple tasks)
   - Requests approval with required items (complex tasks)

### Approval Workflow
1. **Technical Officer** adds required items and submits for approval
2. **Engineer** reviews job and items
3. **Engineer** can modify quantities or add additional items
4. **Engineer** approves/rejects with notes
5. **System** updates job status and creates tasks if approved

### Task Management Workflow
1. **Engineer** creates tasks and assigns multiple employees
2. **Employees** receive task notifications with deadlines
3. **Employees** can request deadline extensions if needed
4. **Engineers** approve/reject extension requests
5. **System** automatically updates timelines upon approval

## 🔍 API Endpoints

### Authentication
```
POST /login          - User authentication
POST /logout         - User logout
GET  /profile        - User profile management
```

### Job Management
```
GET    /jobs                 - List jobs (role-filtered)
POST   /jobs                 - Create new job
GET    /jobs/{id}            - Job details with timeline
PUT    /jobs/{id}            - Update job
DELETE /jobs/{id}            - Soft delete job
POST   /jobs/{id}/approve    - Approve job (Engineer)
```

### Task Management
```
GET    /jobs/{id}/tasks              - List job tasks
POST   /jobs/{id}/tasks              - Create task
PUT    /jobs/{id}/tasks/{taskId}     - Update task
POST   /tasks/{id}/request-extension - Request extension
POST   /extension-requests/{id}/approve - Approve extension
```



## 📊 Performance Features

- **Database Indexing**: Optimized queries for large datasets
- **Eager Loading**: Reduced N+1 query problems
- **Caching**: Redis support for session and cache management
- **Queue System**: Background job processing for notifications

## 🔒 Security Features

- **CSRF Protection**: All forms protected against CSRF attacks
- **SQL Injection Prevention**: Eloquent ORM with prepared statements
- **XSS Protection**: Input sanitization and output escaping
- **Role-Based Access**: Granular permission system
- **Audit Trail**: Complete activity logging for compliance

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



## 👥 Authors

[YourGitHub](https://github.com/ThanujaJeewanthi)

## 🙏 Acknowledgments

- Laravel Framework for providing excellent foundation
- Contributors and testers who helped improve the system
- Organizations that provided real-world use cases for testing

## 📞 Support

For support, email your-thanujajeewanthi@outlook.com or create an issue in this repository.

---
